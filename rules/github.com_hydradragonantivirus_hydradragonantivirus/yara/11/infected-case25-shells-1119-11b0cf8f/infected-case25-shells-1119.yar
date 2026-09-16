rule infected_case25_shells_1119 {
  meta:
    description = "shells - file 1119.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-08-05"
    hash1       = "bcdebcaffcbd0ff1ff38b0d36c252b17b2c6856d45b1084c7b007fae5f26bdc6"

  strings:
    $s1 = "<?php $D=strrev('edoced_46esab');$s=gzinflate($D('7X1te9s2suh3/QqY1QZiItGSnHSzkinbTZxN7uZtY2fbXttHpSRKYi2RKkn5pa7/+50ZACT4JsvZ7t" ascii
    $s2 = "UOtUciBgDSdi1cx29sQissaItIRfq3oZyDwDFMek6F0zSJUpWGtRC6UbAOUSE6RVUZ3gIgnYzQMJPyePi+nsNaaOwcTt0AjuFTPDhDFp6ap6idh6Rmp919DshX40UQIT" ascii
    $s3 = "wiAk2QdhN24daA5qhEcK9HWqAgjY06BvVqUhS2Zh1P0M36ZERKvjQgSYooseWgMJQyroPIpvcMD0V4ymrkZL9gSjdSJk4x2YARM4GYiiaP5JE2DFOUhRn+xsMBU7/sF8" ascii
    $s4 = "dzOpHV6mGkGLND1PvJyb0v+D62R5yMoEE0RmX/xHMvkkdGY4D7DM1AtnBGIPEZn52ZqxRJxMn0rUnuI1QApouoldos56kbwuRl7z6rQZKTOjmHGuLv8Oj16y/GhRh1Uf" ascii
    $s5 = "qOeLOtZyydm6F7447XOCDD2Fu6AgAy6Wu48JZe3FBJS2fmjYe/rYPYjYbh2kcQzKRRmOUBZqtxAzo3Xfs03uynKA69VbRworkbNeo0COZd6Mbr0GdeNBSjItMP6A8gXD" ascii
    $s6 = "iGyWqOTBSCz8Pz+Pycn7cNMpkHqVhOJRVcgOZXU2jG8DdkY5wMBvTVJP0CTdHEHNWC+jds1lK6udOOBih9YnLVOUA6/Fgrdpd6pPTvlXcAzw6BvEEna7EYCJ9XllEiRR" ascii
    $s7 = "z00zCVzYyqqfpm4Bj+ZG+56aL3xeqG7roF0ZlenEg0Cm7k5QxQTaLqCAu27Uf2gEtyK6M2hrbXwEUxWMXR/zr6Sd1Y4DlX0EQwF9VgqK+MNjk7YoE82zk0EEgPzhk9Q2" ascii
    $s8 = "XSRov8r0wtrMggbd0oBoy6tlQ7wRQ2xgh2NP0CaqOwLd6BatCLnHQfOpzA0S8MyD2IFMKjW1e+U1iM76neicLywqdfs5az+S0GqSQhTiquttfrmKLyE/QUZXPg7iPX9e" ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 50KB and
      (all of them)
    ) or (all of them)
}