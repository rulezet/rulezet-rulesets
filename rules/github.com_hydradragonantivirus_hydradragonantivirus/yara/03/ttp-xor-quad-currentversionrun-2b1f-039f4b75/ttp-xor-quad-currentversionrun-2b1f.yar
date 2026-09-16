rule TTP_XOR_QUAD_CurrentVersionRun_2b1f {
  strings:
    $key_2b1f = { 78 70 [2] 5c 7e [2] 77 52 [2] 59 70 [2] 4d 6b [2] 42 71 [2] 5c 6c [2] 5e 6d [2] 45 6b [2] 59 6c [2] 45 43 }

  condition:
    any of them
}