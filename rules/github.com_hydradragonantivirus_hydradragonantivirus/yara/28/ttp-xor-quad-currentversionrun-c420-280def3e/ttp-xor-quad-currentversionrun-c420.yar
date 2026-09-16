rule TTP_XOR_QUAD_CurrentVersionRun_c420 {
  strings:
    $key_c420 = { 97 4f [2] b3 41 [2] 98 6d [2] b6 4f [2] a2 54 [2] ad 4e [2] b3 53 [2] b1 52 [2] aa 54 [2] b6 53 [2] aa 7c }

  condition:
    any of them
}