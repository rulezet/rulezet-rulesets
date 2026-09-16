rule TTP_XOR_QUAD_CurrentVersionRun_523f {
  strings:
    $key_523f = { 01 50 [2] 25 5e [2] 0e 72 [2] 20 50 [2] 34 4b [2] 3b 51 [2] 25 4c [2] 27 4d [2] 3c 4b [2] 20 4c [2] 3c 63 }

  condition:
    any of them
}