rule TTP_XOR_QUAD_CurrentVersionRun_eb2f {
  strings:
    $key_eb2f = { b8 40 [2] 9c 4e [2] b7 62 [2] 99 40 [2] 8d 5b [2] 82 41 [2] 9c 5c [2] 9e 5d [2] 85 5b [2] 99 5c [2] 85 73 }

  condition:
    any of them
}