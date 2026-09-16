rule TTP_XOR_QUAD_CurrentVersionRun_0a0f {
  strings:
    $key_0a0f = { 59 60 [2] 7d 6e [2] 56 42 [2] 78 60 [2] 6c 7b [2] 63 61 [2] 7d 7c [2] 7f 7d [2] 64 7b [2] 78 7c [2] 64 53 }

  condition:
    any of them
}