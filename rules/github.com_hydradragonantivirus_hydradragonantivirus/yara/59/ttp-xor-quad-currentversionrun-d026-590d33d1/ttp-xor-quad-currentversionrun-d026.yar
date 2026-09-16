rule TTP_XOR_QUAD_CurrentVersionRun_d026 {
  strings:
    $key_d026 = { 83 49 [2] a7 47 [2] 8c 6b [2] a2 49 [2] b6 52 [2] b9 48 [2] a7 55 [2] a5 54 [2] be 52 [2] a2 55 [2] be 7a }

  condition:
    any of them
}