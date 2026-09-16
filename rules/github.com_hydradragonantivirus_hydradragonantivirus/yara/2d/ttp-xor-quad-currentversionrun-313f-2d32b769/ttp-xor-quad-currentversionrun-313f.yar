rule TTP_XOR_QUAD_CurrentVersionRun_313f {
  strings:
    $key_313f = { 62 50 [2] 46 5e [2] 6d 72 [2] 43 50 [2] 57 4b [2] 58 51 [2] 46 4c [2] 44 4d [2] 5f 4b [2] 43 4c [2] 5f 63 }

  condition:
    any of them
}