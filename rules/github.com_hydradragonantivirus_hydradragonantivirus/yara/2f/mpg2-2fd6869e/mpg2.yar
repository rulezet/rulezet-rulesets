rule mpg2: MPG {
  meta:
    author = "Joan Bono"

  strings:
    $a = { 00 00 01 BA 44 }

  condition:
    $a at 0
}