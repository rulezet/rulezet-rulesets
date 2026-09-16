rule polycryptpe {
  meta:
    author      = "PEiD"
    description = "PolyCrypt PE 2005 -> JLab Software"
    group       = "444"
    function    = "20"

  strings:
    $a0 = { 60 E8 ED FF FF FF EB }

  condition:
    $a0
}