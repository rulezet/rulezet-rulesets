rule TTP_XOR_QUAD_CurrentVersionRun_501f {
  strings:
    $key_501f = { 03 70 [2] 27 7e [2] 0c 52 [2] 22 70 [2] 36 6b [2] 39 71 [2] 27 6c [2] 25 6d [2] 3e 6b [2] 22 6c [2] 3e 43 }

  condition:
    any of them
}