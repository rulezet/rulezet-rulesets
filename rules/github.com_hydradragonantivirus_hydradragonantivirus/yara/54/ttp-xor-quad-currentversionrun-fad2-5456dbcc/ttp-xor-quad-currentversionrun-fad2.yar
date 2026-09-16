rule TTP_XOR_QUAD_CurrentVersionRun_fad2 {
  strings:
    $key_fad2 = { a9 bd [2] 8d b3 [2] a6 9f [2] 88 bd [2] 9c a6 [2] 93 bc [2] 8d a1 [2] 8f a0 [2] 94 a6 [2] 88 a1 [2] 94 8e }

  condition:
    any of them
}