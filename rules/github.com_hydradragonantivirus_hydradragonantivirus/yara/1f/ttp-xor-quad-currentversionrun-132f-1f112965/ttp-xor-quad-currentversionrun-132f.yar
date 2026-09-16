rule TTP_XOR_QUAD_CurrentVersionRun_132f {
  strings:
    $key_132f = { 40 40 [2] 64 4e [2] 4f 62 [2] 61 40 [2] 75 5b [2] 7a 41 [2] 64 5c [2] 66 5d [2] 7d 5b [2] 61 5c [2] 7d 73 }

  condition:
    any of them
}