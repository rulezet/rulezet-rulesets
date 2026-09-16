rule invalid_trailer_structure_ren: PDF {
  meta:
    author  = "Glenn Edwards (@hiddenillusion)"
    version = "0.1"
    weight  = 1

  strings:
    $magic = "%PDF"
        $reg0  = /trailer\r?\n?.*\/Size.*\r?\n?\.*/
    $reg1  = /\/Root.*\r?\n?.*startxref\r?\n?.*\r?\n?%%EOF/

  condition:
    $magic at 0 and not $reg0 and not $reg1
}