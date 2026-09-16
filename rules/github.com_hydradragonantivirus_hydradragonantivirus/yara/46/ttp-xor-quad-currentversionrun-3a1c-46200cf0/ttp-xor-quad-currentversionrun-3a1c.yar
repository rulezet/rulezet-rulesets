rule TTP_XOR_QUAD_CurrentVersionRun_3a1c {
  strings:
    $key_3a1c = { 69 73 [2] 4d 7d [2] 66 51 [2] 48 73 [2] 5c 68 [2] 53 72 [2] 4d 6f [2] 4f 6e [2] 54 68 [2] 48 6f [2] 54 40 }

  condition:
    any of them
}