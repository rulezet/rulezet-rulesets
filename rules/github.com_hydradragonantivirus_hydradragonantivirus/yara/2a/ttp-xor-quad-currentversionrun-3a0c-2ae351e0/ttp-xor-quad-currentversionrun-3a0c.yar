rule TTP_XOR_QUAD_CurrentVersionRun_3a0c {
  strings:
    $key_3a0c = { 69 63 [2] 4d 6d [2] 66 41 [2] 48 63 [2] 5c 78 [2] 53 62 [2] 4d 7f [2] 4f 7e [2] 54 78 [2] 48 7f [2] 54 50 }

  condition:
    any of them
}