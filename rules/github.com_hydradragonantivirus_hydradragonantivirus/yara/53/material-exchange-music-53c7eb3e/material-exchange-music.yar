rule material_exchange_music: MXF {
  meta:
    author = "Joan Bono"

  strings:
    $a = { 06 0E 2B 34 02 05 01 01 0D 01 02 01 01 02 }

  condition:
    $a at 0
}