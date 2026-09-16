rule TTP_XOR_QUAD_CurrentVersionRun_160f {
  strings:
    $key_160f = { 45 60 [2] 61 6e [2] 4a 42 [2] 64 60 [2] 70 7b [2] 7f 61 [2] 61 7c [2] 63 7d [2] 78 7b [2] 64 7c [2] 78 53 }

  condition:
    any of them
}