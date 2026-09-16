rule TTP_XOR_QUAD_CurrentVersionRun_c42f {
  strings:
    $key_c42f = { 97 40 [2] b3 4e [2] 98 62 [2] b6 40 [2] a2 5b [2] ad 41 [2] b3 5c [2] b1 5d [2] aa 5b [2] b6 5c [2] aa 73 }

  condition:
    any of them
}