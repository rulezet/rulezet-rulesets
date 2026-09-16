rule TTP_XOR_QUAD_CurrentVersionRun_7c3f {
  strings:
    $key_7c3f = { 2f 50 [2] 0b 5e [2] 20 72 [2] 0e 50 [2] 1a 4b [2] 15 51 [2] 0b 4c [2] 09 4d [2] 12 4b [2] 0e 4c [2] 12 63 }

  condition:
    any of them
}