rule TTP_XOR_QUAD_CurrentVersionRun_dd32 {
  strings:
    $key_dd32 = { 8e 5d [2] aa 53 [2] 81 7f [2] af 5d [2] bb 46 [2] b4 5c [2] aa 41 [2] a8 40 [2] b3 46 [2] af 41 [2] b3 6e }

  condition:
    any of them
}