rule TTP_XOR_QUAD_CurrentVersionRun_321f {
  strings:
    $key_321f = { 61 70 [2] 45 7e [2] 6e 52 [2] 40 70 [2] 54 6b [2] 5b 71 [2] 45 6c [2] 47 6d [2] 5c 6b [2] 40 6c [2] 5c 43 }

  condition:
    any of them
}