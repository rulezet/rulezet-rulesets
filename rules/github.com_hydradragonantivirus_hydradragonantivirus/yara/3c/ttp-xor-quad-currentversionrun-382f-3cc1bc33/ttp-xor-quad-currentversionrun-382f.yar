rule TTP_XOR_QUAD_CurrentVersionRun_382f {
  strings:
    $key_382f = { 6b 40 [2] 4f 4e [2] 64 62 [2] 4a 40 [2] 5e 5b [2] 51 41 [2] 4f 5c [2] 4d 5d [2] 56 5b [2] 4a 5c [2] 56 73 }

  condition:
    any of them
}