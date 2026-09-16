rule russian_ransomware_Sept22
{
meta:
	description = "Found on http://abrazivstroy.ru/wp-content/uploads/2015/01/ Tracking full campaign"
	date = "09/22/2015"
	author = "Kevin Perlow"
	note = "The path string will also allow it to pick up the infostealer from the same source. Comment it out if you want"
	note1 = "The smoothtiny string is the best way to catch the fourth piece which didnt contain the unique string"
  reference = "https://www.youtube.com/watch?v=DdkLY99HgAA"
strings:
    $profile1 = "ame View Xerrter Fertui's profile. Viadeo helps professionals like Xerrter Fertui boost their career" wide
	$profile2 = "View Xerrter Fertui's profile. Viadeo helps professionals like Xerrter Fertui boost their career" wide
	$path1 = "\\Gertiopertores\\Certiop.vdp" wide
	$process = "Smoothtiny"
	$compression = "!thiv qrobpam%ccgnnms bg'rsm\"in AIS'hlae."
	$path2 = "AKT -21092015-PowerPoint.exe"
	$path3 = "\\Documents\\chm\\AKT -21092015-PowerPoint.exe" wide
	$path4 = "C:\\Users\\A90B~1\\AppData\\Local\\Temp\\AKT -21092015-PowerPoint.exe"
	$path5 = "C:\\Users\\A90B~1\\AppData\\Local\\Temp\\AKT -21092015-PowerPoint.exe" wide
	$path6 = "AKT -21092015-PowerPoint.exe9" wide
	$path7 = "\\Documents\\chm\\AKT -21092015-PowerPoint.exe" wide
	$path8 = "C:\\Users\\836D~1\\AppData\\Local\\Temp\\PEWER POINT PRESENTATION.exe" wide
	$path9 = "PEWER POINT PRESENTATION.exe=" wide
	$path10 = "\\Documents\\PEWER POINT PRESENTATION.exe"
	$profile3 = "s Ainda precisam da uma melhorada nos pistols, pois a maioria dos jogos ja come" wide
condition:
    	any of them
}