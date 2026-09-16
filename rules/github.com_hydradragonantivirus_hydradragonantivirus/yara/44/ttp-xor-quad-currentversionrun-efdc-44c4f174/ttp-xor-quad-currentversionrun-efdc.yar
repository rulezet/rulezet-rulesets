rule TTP_XOR_QUAD_CurrentVersionRun_efdc {
  strings:
    $key_efdc = { bc b3 [2] 98 bd [2] b3 91 [2] 9d b3 [2] 89 a8 [2] 86 b2 [2] 98 af [2] 9a ae [2] 81 a8 [2] 9d af [2] 81 80 }

  condition:
    any of them
}