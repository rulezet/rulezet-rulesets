rule TTP_XOR_QUAD_CurrentVersionRun_3f6d {
  strings:
    $key_3f6d = { 6c 02 [2] 48 0c [2] 63 20 [2] 4d 02 [2] 59 19 [2] 56 03 [2] 48 1e [2] 4a 1f [2] 51 19 [2] 4d 1e [2] 51 31 }

  condition:
    any of them
}