rule TTP_XOR_QUAD_CurrentVersionRun_4b3f {
  strings:
    $key_4b3f = { 18 50 [2] 3c 5e [2] 17 72 [2] 39 50 [2] 2d 4b [2] 22 51 [2] 3c 4c [2] 3e 4d [2] 25 4b [2] 39 4c [2] 25 63 }

  condition:
    any of them
}