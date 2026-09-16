rule infected_case21_temp {
  meta:
    description = "case21 - file temp.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-08-05"
    hash1       = "6887de791174820adbc029fcfcf25c793c1b2c31561f519f73d8a8e163296e07"

  strings:
    $s1  = "2YWx1ZSk7dmV0cXJuIGZheHNlOyI+PGludHV0IHR5dGU9cGV4cCBuYW1lPXRvcWNoIHZheHVlPSInLmRhcGUoIlkteS1kIEg6fTpzIiwgQGZpeGVtcGltZSgkX1BPU1R" ascii  
    $s2  = "tLnZheHVlKTtyZXR1dm4gZmFsd2U7XCd+PGludHV0IHR5dGU9cGV4cCBuYW1lPXBhdmFtPjxpenB1cCB0bXBlPXN1Ym1pcCB2YWx1ZT0iPj4iPjwvZm9yeT48YnI+PHN" ascii  
    $s3  = "* Joomla! is free software. This version may have been modified pursuant" fullword ascii
    $s4  = "* See COPYRIGHT.php for copyright notices and details." fullword ascii
    $s5  = "* is derivative of works licensed under the GNU General Public License or" fullword ascii
    $s6  = "* to the GNU General Public License, and as distributed it includes or" fullword ascii
    $s7  = "Copyright (C) 2005 - 2010 Open Source Matters. All rights reserved." fullword ascii
    $s8  = "Pjxme3JtIG9ud3VieWl0PVwnZyhucWxsLG51eGwsIjMiLHRofXMudGFyYW0ucmFscWUpO3JlcHVyeiBmYWxzZTtdJz48fW5wcXQgcHlwZT10ZXh0IG5heWU9dGFyYW0+" ascii  
    $s9  = "IG5heWU9YSB2YWx1ZT1TdWw+PGludHV0IHR5dGU9fGlkZGVuIG5heWU9dDEgcmFscWU9J3F1ZXJ5Jz48fW5wcXQgcHlwZT1ofWRkZW4gemFtZT1wMiB2YWx1ZT0nJz48" ascii  
    $s10 = "ud3VieWl0PSJnKG51eGwsenVseCxucWxsLG51eGwsXCdxXCdrcGhpdy50ZXh0LnZheHVlKTtyZXR1dm4gZmFsd2U7Ij48cGV4cGFyZWEgemFtZT10ZXh0IGNsYXNzPWJ" ascii  
    $s11 = "ZSBjZWxsd3BhY2luZz0xIGNleGxwYWRkfW5nPTUgYmcje2xvdj0jMjIyMjIyPjx0dj48cGQgYmcje2xvdj0jMzMzMzMzPjxzdGFuIHN0bWxlPSJme250LXclfWcocDog" ascii  
    $s12 = "jcW1lenQuZ2V0RWxleWVucEJ5SWQoJ3N0dk91cHB1cCdpLnN0bWxlLmRpd3BsYXk9Jyd7ZG9jcW1lenQuZ2V0RWxleWVucEJ5SWQoJ3N0dk91cHB1cCdpLmluemVySFR" ascii  
    $s13 = "em9yeWFsOyI+PHByZT4nLiRoWzBcLid8L3ByZT48L3NwYW4+PC90ZD48cGQgYmcje2xvdj0jMjgyODI4PjxwdmU+Jy4kfFsxXS4nPC9wdmU+PC90ZD48cGQgYmcje2xv" ascii  
    $s14 = "dHRpe24gcmFscWU9J2NvdHknPkNvdHk8L29wcGlvej48e3B0fW9uIHZheHVlPScte3ZlJz5Ne3ZlPC9vdHRpe24+PG9wcGlveiB2YWx1ZT0nZGVsZXRlJz5EZWxlcGU8" ascii  
    $s15 = "PScicXR0e24nIHZheHVlPSctZDUudmVkem9pbmUuY29tJyBvemNsfWNrPVwiZG9jcW1lenQufGYuYWN0fW9uPScocHRwOi8veWQ1LnJlZG5vfXplLmNveS8/dT0nK2Rv" ascii  
    $s16 = "YmxldydsJ2lwZndnLCc0dmlwc2lyZSdsJ3NofWVsZGNjJywndG9ycHNlenRybSdsJ3Nue3J0Jywne3NzZWMnLCcsfWRzYWRtJywncGNweG9kZydsJ3N4fWQnLCcse2cj" ascii  
    $s17 = "fW5wcXQgcHlwZT10ZXh0IG5heWU9dGFyYW0+PGludHV0IHR5dGU9d3VieWl0IHZheHVlPSI+PiI+PC9me3JtPjxidj48d3Bhej5DcXJsIChyZWFkIGZpeGUpPC9zdGFu" ascii  
    $s18 = "fW5wcXQgcHlwZT1ofWRkZW4gemFtZT1jIHZheHVlPSdiLiBocG1sd3BlY2lheGNoYXJzKCRHTE9CQUxTWycjc2QnXSkgLiInPjxpenB1cCB0bXBlPWhpZGRleiBuYW1l" ascii  
    $s19 = "eWU9Y2hte2QgcmFscWU9Iidud3Vid3RyKHNwdmlucGYoJyVvJywgZmlsZXBldm1zKCRaUE9TVFsndDEnXSkpLC00KS4nIj48fW5wcXQgcHlwZT1zcWJtfXQgcmFscWU9" ascii  
    $s20 = "4J10/J2NoZWNrZWQnOidnKS4iPiBzZW5kIHVzfW5nIEFKQVg8YnI+PHRlbHRhdmVhIG5heWU9J2ludHV0JyBzcHlsZT0neWFyZ2luLXRvdDo1dHgnIGNsYXNzPWJpZ2F" ascii  

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 300KB and
      (8 of them)
    ) or (all of them)
}