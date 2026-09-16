rule TTP_XOR_QUAD_CurrentVersionRun_083f {
  strings:
    $key_083f = { 5b 50 [2] 7f 5e [2] 54 72 [2] 7a 50 [2] 6e 4b [2] 61 51 [2] 7f 4c [2] 7d 4d [2] 66 4b [2] 7a 4c [2] 66 63 }

  condition:
    any of them
}