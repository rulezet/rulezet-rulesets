rule PEiD_01524_PE_PaCK_1_0_____C__Copyright_1998_by_ANAKiN__h__ {
  meta:
    description = "[PE-PaCK 1.0 -> (C) Copyright 1998 by ANAKiN (h)]"
    ep_only     = "false"

  strings:
    $a = { C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 0D 0A 20 2D 3D FE 20 50 45 2D 50 41 43 4B 20 76 31 2E 30 20 2D FE 2D 20 28 43 29 20 43 6F 70 }

  condition:
    $a
}