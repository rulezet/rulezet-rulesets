rule TTP_XOR_QUAD_CurrentVersionRun_3aee {
  strings:
    $key_3aee = { 69 81 [2] 4d 8f [2] 66 a3 [2] 48 81 [2] 5c 9a [2] 53 80 [2] 4d 9d [2] 4f 9c [2] 54 9a [2] 48 9d [2] 54 b2 }

  condition:
    any of them
}