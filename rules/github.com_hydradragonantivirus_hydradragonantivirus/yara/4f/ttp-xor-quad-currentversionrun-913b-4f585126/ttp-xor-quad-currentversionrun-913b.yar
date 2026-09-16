rule TTP_XOR_QUAD_CurrentVersionRun_913b {
  strings:
    $key_913b = { c2 54 [2] e6 5a [2] cd 76 [2] e3 54 [2] f7 4f [2] f8 55 [2] e6 48 [2] e4 49 [2] ff 4f [2] e3 48 [2] ff 67 }

  condition:
    any of them
}