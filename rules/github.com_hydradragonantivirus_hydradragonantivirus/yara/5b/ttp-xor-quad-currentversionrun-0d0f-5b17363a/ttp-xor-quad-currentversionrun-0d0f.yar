rule TTP_XOR_QUAD_CurrentVersionRun_0d0f {
  strings:
    $key_0d0f = { 5e 60 [2] 7a 6e [2] 51 42 [2] 7f 60 [2] 6b 7b [2] 64 61 [2] 7a 7c [2] 78 7d [2] 63 7b [2] 7f 7c [2] 63 53 }

  condition:
    any of them
}