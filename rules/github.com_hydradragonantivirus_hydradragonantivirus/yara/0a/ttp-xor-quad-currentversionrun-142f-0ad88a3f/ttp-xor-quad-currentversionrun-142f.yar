rule TTP_XOR_QUAD_CurrentVersionRun_142f {
  strings:
    $key_142f = { 47 40 [2] 63 4e [2] 48 62 [2] 66 40 [2] 72 5b [2] 7d 41 [2] 63 5c [2] 61 5d [2] 7a 5b [2] 66 5c [2] 7a 73 }

  condition:
    any of them
}