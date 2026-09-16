rule TTP_XOR_QUAD_CurrentVersionRun_232f {
  strings:
    $key_232f = { 70 40 [2] 54 4e [2] 7f 62 [2] 51 40 [2] 45 5b [2] 4a 41 [2] 54 5c [2] 56 5d [2] 4d 5b [2] 51 5c [2] 4d 73 }

  condition:
    any of them
}