rule dirac: DRC {
  meta:
    author = "Joan Bono"

  strings:
    $a = "BBCD"

  condition:
    $a at 0
}