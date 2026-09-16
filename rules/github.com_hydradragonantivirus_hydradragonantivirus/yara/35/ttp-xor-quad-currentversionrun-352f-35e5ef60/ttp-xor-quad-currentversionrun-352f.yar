rule TTP_XOR_QUAD_CurrentVersionRun_352f {
  strings:
    $key_352f = { 66 40 [2] 42 4e [2] 69 62 [2] 47 40 [2] 53 5b [2] 5c 41 [2] 42 5c [2] 40 5d [2] 5b 5b [2] 47 5c [2] 5b 73 }

  condition:
    any of them
}