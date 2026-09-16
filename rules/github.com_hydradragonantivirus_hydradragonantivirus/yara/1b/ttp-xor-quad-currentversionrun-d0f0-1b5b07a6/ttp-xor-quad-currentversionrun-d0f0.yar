rule TTP_XOR_QUAD_CurrentVersionRun_d0f0 {
  strings:
    $key_d0f0 = { 83 9f [2] a7 91 [2] 8c bd [2] a2 9f [2] b6 84 [2] b9 9e [2] a7 83 [2] a5 82 [2] be 84 [2] a2 83 [2] be ac }

  condition:
    any of them
}