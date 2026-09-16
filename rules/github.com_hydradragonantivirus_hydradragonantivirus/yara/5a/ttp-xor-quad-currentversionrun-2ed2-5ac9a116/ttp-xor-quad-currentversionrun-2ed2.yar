rule TTP_XOR_QUAD_CurrentVersionRun_2ed2 {
  strings:
    $key_2ed2 = { 7d bd [2] 59 b3 [2] 72 9f [2] 5c bd [2] 48 a6 [2] 47 bc [2] 59 a1 [2] 5b a0 [2] 40 a6 [2] 5c a1 [2] 40 8e }

  condition:
    any of them
}