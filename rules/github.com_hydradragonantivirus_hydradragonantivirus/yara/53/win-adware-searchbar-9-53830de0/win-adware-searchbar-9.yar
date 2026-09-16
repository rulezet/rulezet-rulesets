rule Win_Adware_Searchbar_9
{
strings:
	$a0 = { e3114864aaa6dc0e476371787c7e7fa0acdfcfc7034160a8ac1c4e677379b93e5fffac1b3de600687474703a2f2f7777772e6e6175706f69 }


condition:
	$a0
}