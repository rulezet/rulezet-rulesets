rule PEiD_03423_Vx__Trojan_Telefoon_ {
  meta:
    description = "[Vx: Trojan.Telefoon]"
    ep_only     = "true"

  strings:
    $a = { 60 1E E8 3B 01 BF CC 01 2E 03 3E CA 01 2E C7 05 }

  condition:
    $a
}