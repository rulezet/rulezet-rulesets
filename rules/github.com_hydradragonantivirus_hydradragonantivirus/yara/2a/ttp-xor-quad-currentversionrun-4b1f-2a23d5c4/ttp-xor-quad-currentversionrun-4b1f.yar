rule TTP_XOR_QUAD_CurrentVersionRun_4b1f {
  strings:
    $key_4b1f = { 18 70 [2] 3c 7e [2] 17 52 [2] 39 70 [2] 2d 6b [2] 22 71 [2] 3c 6c [2] 3e 6d [2] 25 6b [2] 39 6c [2] 25 43 }

  condition:
    any of them
}