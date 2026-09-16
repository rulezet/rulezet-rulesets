rule TTP_XOR_QUAD_CurrentVersionRun_3e0c {
  strings:
    $key_3e0c = { 6d 63 [2] 49 6d [2] 62 41 [2] 4c 63 [2] 58 78 [2] 57 62 [2] 49 7f [2] 4b 7e [2] 50 78 [2] 4c 7f [2] 50 50 }

  condition:
    any of them
}