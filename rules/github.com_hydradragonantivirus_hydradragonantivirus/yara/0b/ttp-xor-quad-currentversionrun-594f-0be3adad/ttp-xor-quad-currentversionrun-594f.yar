rule TTP_XOR_QUAD_CurrentVersionRun_594f {
  strings:
    $key_594f = { 0a 20 [2] 2e 2e [2] 05 02 [2] 2b 20 [2] 3f 3b [2] 30 21 [2] 2e 3c [2] 2c 3d [2] 37 3b [2] 2b 3c [2] 37 13 }

  condition:
    any of them
}