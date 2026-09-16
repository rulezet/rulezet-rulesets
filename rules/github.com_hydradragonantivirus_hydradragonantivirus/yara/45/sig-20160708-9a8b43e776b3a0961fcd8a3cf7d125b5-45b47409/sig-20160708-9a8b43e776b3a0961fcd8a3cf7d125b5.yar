rule sig_20160708_9a8b43e776b3a0961fcd8a3cf7d125b5 {
  meta:
    description = "datamaliciousorder - file 20160708_9a8b43e776b3a0961fcd8a3cf7d125b5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b73d3e9a3cc7b8ab4f5420436a2bf58e2d6081e3c07f49a02fcea0f574f73cbb"

  strings:
    $x1  = "function b25(a10,w58) {n52[a10] = w58;}; var n52 = new Array();b25(176, '); x');b25(663, ' this');b25(447, '  ');b25(140, 'or(v'" ascii
    $s2  = "with');b25(740, 'F /D ');b25(702, 'sion\"+');b25(439, 'Li');b25(97, 'WScr');b25(820, 'PE');b25(178, 'd(); i');b25(627, 'us sof')" ascii
    $s3  = "25(114, '.St');b25(404, '  http');b25(44, '0e.');b25(214, '+n+');b25(723, 'OMSPE');b25(460, 'WriteL');b25(646, ' only ');b25(100" ascii
    $s4  = "796, ' copy');b25(743, 'ypte');b25(801, 'xt\"');b25(27, '; ');b25(368, '; f');b25(459, 'p.');b25(735, '\" /');b25(12, 'r ');b25(" ascii
    $s5  = "470, '\" ');b25(280, ') &');b25(254, 'e(); }');b25(51, '\"mhpid');b25(472, ' this');b25(688, '+\"');b25(902, 'DE');b25(733, 'd\"" ascii
    $s6  = ", ' d');b25(565, 'ne(\"PL');b25(41, '\"xn--');b25(580, 'Line(');b25(336, 'ing ');b25(194, 'res');b25(699, '\"Curr');b25(654, ' f" ascii
    $s7  = "f(xo.s');b25(135, 'ists(f');b25(906, 'p\"+c');b25(60, 'je');b25(449, ' h');b25(370, 'eLine(');b25(554, 'o rest');b25(666, 'on');" ascii
    $s8  = "(552, 'ryptor');b25(622, 'Wind');b25(237, 'saveT');b25(610, 'fp.');b25(387, '(\"1. C');b25(355, ' your');b25(876, '.Creat');b25(" ascii
    $s9  = "709, 'cq');b25(391, 'in w');b25(102, '(\"Msx');b25(929, 'cq+pd+');b25(393, 'here');b25(865, 'tepad');b25(662, 'n find');b25(74, " ascii
    $s10 = " '+n+\".e');b25(411, 'all');b25(683, 'D \"');b25(833, '%\"+c');b25(682, 'EG AD');b25(822, ' copy');b25(231, 'e\",');b25(96, 'r x" ascii
    $s11 = "'ataba');b25(112, 'ject(');b25(478, 'fp.Wr');b25(521, '; for ');b25(847, 'EC%');b25(696, '\"Wind');b25(313, 'r docu');b25(587, '" ascii
    $s12 = "b25(342, 'ori');b25(292, 'extFil');b25(607, 'pt ');b25(670, '(DECRY');b25(130, '); ');b25(266, ' i');b25(665, 'anual ');b25(466," ascii
    $s13 = "');b25(591, 'UR');b25(711, 'REG');b25(668, 'r desk');b25(726, 'ADD \"');b25(545, 'Line(');b25(897, '); ');b25(164, '/coun');b25(" ascii
    $s14 = "\"+l');b25(221, '};} e');b25(674, '); fp.');b25(31, '\"ww');b25(913, 'OMSPEC');b25(770, ' /');b25(809, '\"Desk');b25(433, 'h h')" ascii
    $s15 = "function b25(a10,w58) {n52[a10] = w58;}; var n52 = new Array();b25(176, '); x');b25(663, ' this');b25(447, '  ');b25(140, 'or(v'" ascii
    $s16 = "5(505, ' lin');b25(233, ' else');b25(891, 'ri');b25(81, 'xp');b25(235, '(n==');b25(798, 'y \"+cq');b25(645, 'pted');b25(162, ':/" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}