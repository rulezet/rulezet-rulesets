rule TTP_XOR_QUAD_CurrentVersionRun_cc32 {
  strings:
    $key_cc32 = { 9f 5d [2] bb 53 [2] 90 7f [2] be 5d [2] aa 46 [2] a5 5c [2] bb 41 [2] b9 40 [2] a2 46 [2] be 41 [2] a2 6e }

  condition:
    any of them
}