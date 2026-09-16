rule TTP_XOR_QUAD_CurrentVersionRun_915d {
  strings:
    $key_915d = { c2 32 [2] e6 3c [2] cd 10 [2] e3 32 [2] f7 29 [2] f8 33 [2] e6 2e [2] e4 2f [2] ff 29 [2] e3 2e [2] ff 01 }

  condition:
    any of them
}