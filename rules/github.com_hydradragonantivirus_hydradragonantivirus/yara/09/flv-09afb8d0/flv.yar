rule flv: FLV {
  meta:
    author = "Joan Bono"

  strings:
    $a = { 46 4C 56 01 }

  condition:
    $a at 0
}