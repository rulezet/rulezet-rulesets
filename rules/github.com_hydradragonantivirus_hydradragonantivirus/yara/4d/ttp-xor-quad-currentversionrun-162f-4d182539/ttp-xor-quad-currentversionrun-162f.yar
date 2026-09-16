rule TTP_XOR_QUAD_CurrentVersionRun_162f {
  strings:
    $key_162f = { 45 40 [2] 61 4e [2] 4a 62 [2] 64 40 [2] 70 5b [2] 7f 41 [2] 61 5c [2] 63 5d [2] 78 5b [2] 64 5c [2] 78 73 }

  condition:
    any of them
}