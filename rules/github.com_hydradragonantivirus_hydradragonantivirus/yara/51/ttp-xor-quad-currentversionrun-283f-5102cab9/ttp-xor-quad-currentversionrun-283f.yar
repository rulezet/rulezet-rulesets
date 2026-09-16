rule TTP_XOR_QUAD_CurrentVersionRun_283f {
  strings:
    $key_283f = { 7b 50 [2] 5f 5e [2] 74 72 [2] 5a 50 [2] 4e 4b [2] 41 51 [2] 5f 4c [2] 5d 4d [2] 46 4b [2] 5a 4c [2] 46 63 }

  condition:
    any of them
}