rule TTP_XOR_QUAD_CurrentVersionRun_cccd {
  strings:
    $key_cccd = { 9f a2 [2] bb ac [2] 90 80 [2] be a2 [2] aa b9 [2] a5 a3 [2] bb be [2] b9 bf [2] a2 b9 [2] be be [2] a2 91 }

  condition:
    any of them
}