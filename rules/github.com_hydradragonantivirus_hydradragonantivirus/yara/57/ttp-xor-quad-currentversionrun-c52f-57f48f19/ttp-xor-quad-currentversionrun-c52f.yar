rule TTP_XOR_QUAD_CurrentVersionRun_c52f {
  strings:
    $key_c52f = { 96 40 [2] b2 4e [2] 99 62 [2] b7 40 [2] a3 5b [2] ac 41 [2] b2 5c [2] b0 5d [2] ab 5b [2] b7 5c [2] ab 73 }

  condition:
    any of them
}