rule suspicious_js_ren: PDF {
  meta:
    author  = "Glenn Edwards (@hiddenillusion)"
    version = "0.1"
    weight  = 3

  strings:
    $magic = "%PDF"

    $attrib0 = /\/OpenAction /
    $attrib1 = /\/JavaScript /

    $js0 = "eval"
    $js1 = "Array"
    $js2 = "String.fromCharCode"

  condition:
    $magic at 0 and all of ($attrib*) and 2 of ($js*)
}