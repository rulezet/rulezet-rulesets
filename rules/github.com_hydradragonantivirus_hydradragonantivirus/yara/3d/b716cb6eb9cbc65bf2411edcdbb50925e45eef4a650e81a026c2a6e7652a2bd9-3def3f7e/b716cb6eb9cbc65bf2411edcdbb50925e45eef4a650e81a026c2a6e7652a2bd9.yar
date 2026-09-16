rule b716cb6eb9cbc65bf2411edcdbb50925e45eef4a650e81a026c2a6e7652a2bd9 {
  meta:
    description = "datamaliciousorder - file b716cb6eb9cbc65bf2411edcdbb50925e45eef4a650e81a026c2a6e7652a2bd9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b716cb6eb9cbc65bf2411edcdbb50925e45eef4a650e81a026c2a6e7652a2bd9"

  strings:
    $s1 = "function OVelwVqBygWSidYTdSFNhDpCTejHWJqWNzSPWShDTvvAubfMaDJUYkT (vskEQEyrisxuztQhrLAFGhuhhLISHlAarxLmNcmjGgXNaszqRdBBgFMNyDX)" fullword ascii
    $s2 = "function ptxuuJWfiJJVhveXdxXTOtYGtwdzMzgkBEdYKwthQuOpzXnmdyA( hHtCeJPHqAKdErCBsRZffIWOtaKlgQszEOpbkQEdJSRWNeIfnFunHrpYkfIDzeaZHL" ascii
    $s3 = "function ptxuuJWfiJJVhveXdxXTOtYGtwdzMzgkBEdYKwthQuOpzXnmdyA( hHtCeJPHqAKdErCBsRZffIWOtaKlgQszEOpbkQEdJSRWNeIfnFunHrpYkfIDzeaZHL" ascii
    $s4 = "  return EvgkwsWDBieTPYRzaKgGoMRBdjyulkyoKFhnZwaVDoxImJmcOFmCRwisdfG.nodeTypedValue ;" fullword ascii

  condition:
    uint16(0) == 0x4e47 and
    all of them
}